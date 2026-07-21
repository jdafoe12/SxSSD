#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Include the policy so this test drives its actual static NVMe callback. */
#include "../tee-ftl-v4-policy.c"

static uint8_t mock_host_input[TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES];
static uint8_t mock_host_output[TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES];
static uint32_t mock_host_input_bytes;
static uint32_t mock_host_output_bytes;
static int promotion_storage_result;
static int promotion_commit_result;

static int test_transaction_flush(
    void *opaque, const struct tee_v4_transaction_record *records,
    uint32_t count)
{
    (void)opaque;
    assert(records != NULL && count == 1);
    g_v4_transaction_sink[0] = records[0];
    g_v4_transaction_sink[0].state = TEE_V4_TRANSACTION_PERSISTED;
    g_v4_transaction_sink_count = 1;
    return 0;
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

static int observed_v4_promotion(
    void *opaque, const struct tee_v2_cache *cache,
    const struct tee_v2_passive_metadata *passive)
{
    promotion_storage_result = tee_v3_policy_persist_promotion(
        opaque, cache, passive);
    if (promotion_storage_result != 0) return -1;
    promotion_commit_result = tee_v4_writeback_commit_chunk(
        &g_v4_writeback, passive->file_id, passive->chunk_id);
    return promotion_commit_result;
}

static uint16_t mock_read_cmd_buffer(struct NvmeCommandEvent *event,
                                     void *dst, uint32_t length)
{
    (void)event;
    if (length != mock_host_input_bytes) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    memcpy(dst, mock_host_input, length);
    return NVME_SUCCESS;
}

static uint16_t mock_write_cmd_buffer(struct NvmeCommandEvent *event,
                                      const void *src, uint32_t length)
{
    (void)event;
    assert(length <= sizeof(mock_host_output));
    memcpy(mock_host_output, src, length);
    mock_host_output_bytes = length;
    return NVME_SUCCESS;
}

static size_t make_query(uint16_t command_type, uint64_t request_id)
{
    struct tee_v4_admin_request_header *header =
        (void *)mock_host_input;
    struct tee_v4_admin_chunk_query_payload *payload =
        (void *)(mock_host_input + sizeof(*header));
    size_t bytes = sizeof(*header) + sizeof(*payload);

    memset(mock_host_input, 0, sizeof(mock_host_input));
    header->magic = TEE_V4_ADMIN_MAGIC;
    header->version = TEE_V4_ADMIN_VERSION;
    header->command_type = command_type;
    header->request_id = request_id;
    header->payload_len = sizeof(*payload);
    header->flags = TEE_V4_ADMIN_FLAG_SUBMIT;
    payload->file_id = 12;
    payload->chunk_id = 34;
    payload->page_size = 2;
    assert(tee_v4_admin_sign_request(mock_host_input, bytes) == 0);
    return bytes;
}

static size_t make_control(uint32_t flags, uint16_t command_type,
                           uint64_t request_id,
                           uint32_t page_index)
{
    struct tee_v4_admin_request_header *header =
        (void *)mock_host_input;
    size_t bytes = sizeof(*header);

    memset(mock_host_input, 0, sizeof(mock_host_input));
    header->magic = TEE_V4_ADMIN_MAGIC;
    header->version = TEE_V4_ADMIN_VERSION;
    header->command_type = command_type;
    header->request_id = request_id;
    header->flags = flags;
    if (flags == TEE_V4_ADMIN_FLAG_CONTINUE) {
        struct tee_v4_admin_continue_payload *payload =
            (void *)(mock_host_input + sizeof(*header));
        payload->request_id = request_id;
        payload->page_index = page_index;
        header->payload_len = sizeof(*payload);
        bytes += sizeof(*payload);
    }
    assert(tee_v4_admin_sign_request(mock_host_input, bytes) == 0);
    return bytes;
}

static size_t make_metadata_intake(
    uint64_t request_id,
    const uint8_t segments[4][TEE_V2_DEFAULT_SEGMENT_SIZE])
{
    struct tee_v4_admin_request_header *header =
        (void *)mock_host_input;
    struct tee_v4_admin_active_metadata_payload *payload =
        (void *)(mock_host_input + sizeof(*header));
    struct tee_v4_admin_hmac_group_wire *groups = (void *)(payload + 1);
    size_t payload_bytes = sizeof(*payload) + 4 * sizeof(*groups);
    size_t bytes = sizeof(*header) + payload_bytes;
    uint32_t i;

    memset(mock_host_input, 0, sizeof(mock_host_input));
    header->magic = TEE_V4_ADMIN_MAGIC;
    header->version = TEE_V4_ADMIN_VERSION;
    header->command_type = TEE_V4_ADMIN_CMD_SET_ACTIVE_METADATA;
    header->request_id = request_id;
    header->payload_len = (uint32_t)payload_bytes;
    header->flags = TEE_V4_ADMIN_FLAG_SUBMIT;
    payload->file_id = 12;
    payload->chunk_id = 34;
    payload->chunk_size_bytes = 2048;
    payload->segment_count = 4;
    payload->number_coefficient = 2;
    payload->group_count = 4;
    for (i = 0; i < 4; i++) {
        groups[i].start_segment_index = i + 1;
        groups[i].group_segment_count = 1;
        tee_v2_hmac_sha256(tee_v2_prototype_key,
                           TEE_V2_PROTOTYPE_KEY_SIZE,
                           segments[i], TEE_V2_DEFAULT_SEGMENT_SIZE,
                           groups[i].expected_hmac);
    }
    assert(tee_v4_admin_sign_request(mock_host_input, bytes) == 0);
    return bytes;
}

static void dispatch(uint8_t opcode, uint32_t request_bytes,
                     struct FtlPolicyAPI *api)
{
    TeeV4NvmeCmd command;
    struct NvmeCommandEvent event;

    memset(&command, 0, sizeof(command));
    memset(&event, 0, sizeof(event));
    command.cdw12 = request_bytes;
    event.opcode = opcode;
    event.is_admin = true;
    event.cmd = (void *)&command;
    mock_host_input_bytes = request_bytes;
    mock_host_output_bytes = 0;
    assert(tee_v4_admin_condition(NULL, &event, api, NULL));
    (void)tee_v4_admin_callback(NULL, &event, api, NULL);
    assert(event.status == NVME_SUCCESS);
}

static void test_continuous_v4_nvme_flow(void)
{
    struct FtlPolicyAPI api;
    struct block_policy_context intake_context;
    struct tee_v2_active_metadata bootstrap_active;
    struct tee_v2_hmac_group_spec bootstrap_group;
    uint8_t bootstrap_hmac[TEE_V2_HMAC_SIZE] = {0};
    uint8_t segments[4][TEE_V2_DEFAULT_SEGMENT_SIZE];
    struct tee_v4_admin_response_header *response =
        (void *)mock_host_output;
    uint64_t *locations = (void *)(response + 1);
    uint32_t i;
    size_t bytes;

    memset(&api, 0, sizeof(api));
    api.read_cmd_buffer = mock_read_cmd_buffer;
    api.write_cmd_buffer = mock_write_cmd_buffer;

    assert(tee_v1_segment_layout_init(&g_v1_layout, 300, 512, 64));
    assert(tee_v2_format_config_init(&g_v2_config,
                                     TEE_V2_DEFAULT_SEGMENT_SIZE, 4096));
    bootstrap_group.start_segment_index = 1;
    bootstrap_group.group_segment_count = 1;
    bootstrap_group.expected_hmac = bootstrap_hmac;
    assert(tee_v2_active_metadata_init(
               &bootstrap_active, &g_v2_config, 99, 1, 512, 1, 1,
               &bootstrap_group, 1) == 0);
    assert(tee_v2_cache_init(&g_v2_cache, g_v1_layout.visible_segments,
                             8) == 0);
    assert(tee_v2_write_context_init(&g_v2_write, &bootstrap_active,
                                     &g_v2_cache,
                                     g_v1_layout.visible_segments) == 0);
    g_v2_active = bootstrap_active;
    g_v2_active_valid = true;
    g_v2_write.active = &g_v2_active;
    memset(&intake_context, 0, sizeof(intake_context));
    g_ctx = &intake_context;

    g_v4_backend.capacity = (size_t)(g_v1_layout.hidden_lba_count *
                                     g_v1_layout.lba_size);
    g_v4_backend.bytes = calloc(g_v4_backend.capacity, 1);
    assert(g_v4_backend.bytes != NULL);
    assert(tee_v3_storage_init(&g_v4_storage, &g_v1_layout,
                               tee_v4_write_hidden_image,
                               &g_v4_backend) == 0);
    tee_v3_policy_context_init(&g_v4_policy, &g_v2_write, &g_v4_storage);
    g_v4_transaction_sink_count = 0;
    assert(tee_v4_writeback_init(
               &g_v4_writeback, g_v4_pending_transactions,
               TEE_V4_DEFAULT_RELOCATION_BATCH_MAX,
               TEE_V4_DEFAULT_RELOCATION_TIMEOUT_OPS,
               test_transaction_flush, NULL) == 0);
    promotion_storage_result = promotion_commit_result = 99;
    tee_v2_write_set_promotion_hook(&g_v2_write,
                                    observed_v4_promotion,
                                    &g_v4_policy);
    assert(tee_v4_admin_init(&g_v4_admin, &g_v4_policy,
                             TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES, 4096) == 0);
    tee_v4_admin_set_metadata_intake(&g_v4_admin,
                                     tee_v4_intake_active_metadata, NULL);

    for (i = 0; i < 4; i++) {
        memset(segments[i], (int)(i + 1), sizeof(segments[i]));
        segments[i][0] = TEE_V2_SEGMENT_MAGIC;
        segments[i][1] = 12;
        segments[i][2] = 34;
        segments[i][3] = 0;
        segments[i][4] = 0;
        segments[i][5] = (uint8_t)(i + 1);
        segments[i][6] = 0;
        segments[i][7] = 0;
        segments[i][8] = 0;
    }
    bytes = make_metadata_intake(899, segments);
    dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api);
    assert(g_v2_active_valid);
    assert(g_v2_active.file_id == 12 && g_v2_active.chunk_id == 34);
    {
        struct tee_v2_hmac_group_spec invalid_group;
        uint8_t invalid_hmac[TEE_V2_HMAC_SIZE] = {0};

        invalid_group.start_segment_index = 5;
        invalid_group.group_segment_count = 1;
        invalid_group.expected_hmac = invalid_hmac;
        assert(tee_v2_policy_set_active_metadata(
                   13, 35, 2048, 4, 2, &invalid_group, 1) != 0);
        assert(g_v2_active_valid);
        assert(g_v2_active.file_id == 12 && g_v2_active.chunk_id == 34);
        assert(g_v2_write.active == &g_v2_active);
    }

    /* The block-media fixture is unavailable; this is the exact post-media
     * policy operation used by the inherited normal NVMe WRITE callback. */
    for (i = 0; i < 4; i++) {
        enum tee_v2_write_result result = tee_v2_apply_segment_after_media(
            &g_v2_write, true, 101 + i, segments[i], sizeof(segments[i]));
        assert(result != TEE_V2_WRITE_ERROR && result != TEE_V2_WRITE_REJECTED);
    }
    assert(g_v2_write.active_promoted);
    assert(promotion_storage_result == 0);
    assert(promotion_commit_result == 0);
    assert(g_v4_backend.size > 0);
    assert(g_v4_transaction_sink_count == 1);
    assert(g_v4_transaction_sink[0].type == TEE_V4_TRANSACTION_CHUNK_COMMIT);

    bytes = make_query(TEE_V4_ADMIN_CMD_READ_SUMMARY, 900);
    dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api);
    bytes = make_control(TEE_V4_ADMIN_FLAG_FETCH,
                         TEE_V4_ADMIN_CMD_READ_SUMMARY, 900, 0);
    dispatch(TEE_V4_ADMIN_FETCH_OPCODE, (uint32_t)bytes, &api);
    assert(response->total_items == 1);

    /* A persisted V3 promotion is complete even if audit commit fails. */
    {
        struct tee_v2_passive_metadata *passive =
            tee_v2_cache_find_passive(&g_v2_cache, 12, 34);
        assert(passive != NULL);
        assert(tee_v4_writeback_init(
                   &g_v4_writeback, g_v4_pending_transactions,
                   TEE_V4_DEFAULT_RELOCATION_BATCH_MAX,
                   TEE_V4_DEFAULT_RELOCATION_TIMEOUT_OPS,
                   fail_transaction_flush, NULL) == 0);
        assert(tee_v4_persist_promotion(
                   &g_v4_policy, &g_v2_cache, passive) == 0);
        assert(g_v4_backend.size > 0);
    }

    /* Generic successful operations, including fallback writes, age a
     * pending relocation to its timeout even when no later relocation occurs. */
    assert(tee_v4_writeback_init(
               &g_v4_writeback, g_v4_pending_transactions,
               TEE_V4_DEFAULT_RELOCATION_BATCH_MAX, 3,
               test_transaction_flush, NULL) == 0);
    tee_v2_write_set_operation_advance(&g_v2_write,
                                       tee_v4_advance_operation,
                                       &g_v4_writeback);
    assert(tee_v4_writeback_reserve_relocation(
               &g_v4_writeback, 12, 34, 1, 101, 201) == 0);
    assert(tee_v2_write_advance_operation(&g_v2_write, 1) == 0);
    assert(g_v4_writeback.pending_count == 1);
    assert(tee_v2_write_advance_operation(&g_v2_write, 2) == 0);
    assert(g_v4_writeback.pending_count == 0);
    assert(((struct tee_v3_read_summary *)(response + 1))->segment_count == 4);

    bytes = make_query(TEE_V4_ADMIN_CMD_READ_LOCATIONS, 901);
    dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api);
    bytes = make_control(TEE_V4_ADMIN_FLAG_FETCH,
                         TEE_V4_ADMIN_CMD_READ_LOCATIONS, 901, 0);
    dispatch(TEE_V4_ADMIN_FETCH_OPCODE, (uint32_t)bytes, &api);
    assert(mock_host_output_bytes == sizeof(*response) + 2 * sizeof(uint64_t));
    assert(response->total_items == 4);
    assert(response->total_pages == 2);
    assert(locations[0] == 101 && locations[1] == 102);
    bytes = make_control(TEE_V4_ADMIN_FLAG_CONTINUE,
                         TEE_V4_ADMIN_CMD_READ_LOCATIONS, 901, 1);
    dispatch(TEE_V4_ADMIN_CONTINUE_OPCODE, (uint32_t)bytes, &api);
    assert(locations[0] == 103 && locations[1] == 104);

    bytes = make_query(TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS, 902);
    dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api);
    bytes = make_control(TEE_V4_ADMIN_FLAG_FETCH,
                         TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS, 902, 0);
    dispatch(TEE_V4_ADMIN_FETCH_OPCODE, (uint32_t)bytes, &api);
    assert(response->total_items == 4);
    assert(response->total_pages == 2);
    bytes = make_control(TEE_V4_ADMIN_FLAG_CONTINUE,
                         TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS, 902, 1);
    dispatch(TEE_V4_ADMIN_CONTINUE_OPCODE, (uint32_t)bytes, &api);
    assert(response->page_index == 1);

    bytes = make_query(TEE_V4_ADMIN_CMD_ONE_BIT_PROOF, 903);
    dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api);
    bytes = make_control(TEE_V4_ADMIN_FLAG_FETCH,
                         TEE_V4_ADMIN_CMD_ONE_BIT_PROOF, 903, 0);
    dispatch(TEE_V4_ADMIN_FETCH_OPCODE, (uint32_t)bytes, &api);
    assert(response->total_items == 1);

    tee_v4_admin_destroy(&g_v4_admin);
    tee_v2_write_context_destroy(&g_v2_write);
    tee_v2_cache_destroy(&g_v2_cache);
    tee_v2_active_metadata_destroy(&g_v2_active);
    free(g_v4_backend.bytes);
    g_ctx = NULL;
}

int main(void)
{
    test_continuous_v4_nvme_flow();
    puts("test_tee_v4_policy_flow: PASS");
    return 0;
}
