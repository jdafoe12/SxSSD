#define TEE_V4_POLICY_INIT_NAME tee_v4_standalone_init_policy
#include "tee-ftl-v4-policy.c"
#undef TEE_V4_POLICY_INIT_NAME

#include "tee-ftl-v5-policy.h"
#include "tee/tee-v5-admin.h"
#include "tee/tee-v5-delete.h"
#include "tee/tee-v5-proof.h"
#include "tee/tee-v5-status.h"

static struct tee_v5_admin g_v5_admin;

static int tee_v5_init_failed(void)
{
    tee_v5_admin_destroy(&g_v5_admin);
    return -1;
}

static int tee_v5_persist_delete(
    void *opaque, const struct tee_v1_bitmap *protected_bitmap,
    const struct tee_v2_passive_metadata *records, uint32_t record_count)
{
    return tee_v3_storage_persist(opaque, protected_bitmap, records,
                                  record_count);
}

static int tee_v5_intake_active_metadata(
    void *opaque,
    const struct tee_v4_admin_active_metadata_payload *metadata,
    const struct tee_v4_admin_hmac_group_wire *groups)
{
    struct tee_v3_policy_context *policy = opaque;
    int result;

    if (g_v2_active_valid &&
        (g_v2_active.file_id != metadata->file_id ||
         g_v2_active.chunk_id != metadata->chunk_id))
        return 2;
    result = tee_v4_intake_active_metadata(NULL, metadata, groups);
    if (result == 0 && policy)
        tee_v5_proof_clear_error(&policy->pending, metadata->file_id,
                                 metadata->chunk_id);
    return result;
}

static int tee_v5_abort_active_handler(void *opaque, uint8_t file_id,
                                       uint32_t chunk_id)
{
    (void)opaque;
    if (g_v2_active_valid && g_v2_active.file_id == file_id &&
        g_v2_active.chunk_id == chunk_id) {
        tee_v2_active_metadata_destroy(&g_v2_active);
        memset(&g_v2_active, 0, sizeof(g_v2_active));
        g_v2_active_valid = false;
        g_v2_write.active = NULL;
        g_v2_write.active_promoted = false;
        memset(g_v2_write.pending_bitmap.bits, 0,
               g_v2_write.pending_bitmap.byte_count);
        tee_v5_proof_clear_error(&g_v4_policy.pending, file_id, chunk_id);
    }
    return 0;
}

static int tee_v5_delete_chunk_handler(void *opaque, uint8_t file_id,
                                       uint32_t chunk_id)
{
    struct tee_v3_policy_context *policy = opaque;
    enum tee_v5_delete_result result;
    uint32_t failed_segment = TEE_V5_NO_FAILED_SEGMENT;

    if (!policy || !policy->write || !policy->write->cache) return -2;
    if (g_v2_active_valid && g_v2_active.file_id == file_id &&
        g_v2_active.chunk_id == chunk_id) {
        (void)tee_v5_proof_record_error(
            &policy->pending, file_id, chunk_id,
            TEE_V5_PROOF_ERROR_DELETE_CONFLICT, TEE_V5_NO_FAILED_SEGMENT);
        return 2;
    }
    if (!tee_v2_cache_find_passive(policy->write->cache, file_id, chunk_id))
        return 1;
    if (tee_v4_writeback_sync(&g_v4_writeback) != 0) {
        (void)tee_v5_proof_record_error(
            &policy->pending, file_id, chunk_id,
            TEE_V5_PROOF_ERROR_PERSISTENCE_FAILURE,
            TEE_V5_NO_FAILED_SEGMENT);
        return -2;
    }
    result = tee_v5_delete_chunk(policy->write->cache, file_id, chunk_id,
                                 tee_v5_persist_delete, policy->storage,
                                 &failed_segment);
    if (result == TEE_V5_DELETE_OK) {
        tee_v5_proof_clear_error(&policy->pending, file_id, chunk_id);
        return 0;
    }
    if (result == TEE_V5_DELETE_NOT_FOUND) return 1;
    (void)tee_v5_proof_record_error(
        &policy->pending, file_id, chunk_id,
        result == TEE_V5_DELETE_INTEGRITY ?
            TEE_V5_PROOF_ERROR_DELETE_INTEGRITY :
            TEE_V5_PROOF_ERROR_PERSISTENCE_FAILURE,
        failed_segment);
    return -2;
}

static bool tee_v5_admin_condition(struct ssd *ssd,
                                   struct NvmeCommandEvent *event,
                                   struct FtlPolicyAPI *api, void *context)
{
    (void)ssd; (void)api; (void)context;
    return event->is_admin &&
           (event->opcode == TEE_V4_ADMIN_SUBMIT_OPCODE ||
            event->opcode == TEE_V4_ADMIN_FETCH_OPCODE ||
            event->opcode == TEE_V4_ADMIN_CONTINUE_OPCODE);
}

static uint64_t tee_v5_admin_callback(struct ssd *ssd,
                                      struct NvmeCommandEvent *event,
                                      struct FtlPolicyAPI *api, void *context)
{
    const TeeV4NvmeCmd *cmd = event->cmd;
    uint32_t length;
    uint8_t *buffer;
    uint8_t *response = NULL;
    size_t written = 0;
    int result;
    (void)ssd; (void)context;
    if (!cmd || !api || !api->read_cmd_buffer || !api->write_cmd_buffer) {
        event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR; return 0;
    }
    length = cmd->cdw12;
    if (!length || length > TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES) {
        event->status = NVME_INVALID_FIELD | NVME_DNR; return 0;
    }
    buffer = calloc(1, length);
    if (!buffer) { event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR; return 0; }
    event->status = api->read_cmd_buffer(event, buffer, length);
    if (event->status != NVME_SUCCESS) { free(buffer); return 0; }
    if (event->opcode == TEE_V4_ADMIN_SUBMIT_OPCODE) {
        result = tee_v5_admin_submit(&g_v5_admin, buffer, length);
        event->status = result == -2 ? NVME_INTERNAL_DEV_ERROR :
                        result ? (NVME_INVALID_FIELD | NVME_DNR) : NVME_SUCCESS;
        free(buffer); return 0;
    }
    response = calloc(1, TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES);
    if (!response) { free(buffer); event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR; return 0; }
    result = event->opcode == TEE_V4_ADMIN_FETCH_OPCODE ?
        tee_v5_admin_fetch(&g_v5_admin, buffer, length, response,
                           TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES, &written) :
        tee_v5_admin_continue(&g_v5_admin, buffer, length, response,
                              TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES, &written);
    event->status = result ? (NVME_INVALID_FIELD | NVME_DNR) :
                    api->write_cmd_buffer(event, response, (uint32_t)written);
    free(response); free(buffer); return 0;
}

int init_policy(struct ssd *ssd, struct FtlPolicyAPI *api)
{
    int submit, fetch;
    if (!api || !api->register_admin_hook || !api->unregister_admin_hook ||
        tee_v4_policy_state_init(ssd, api) != 0 ||
        tee_v5_admin_init(&g_v5_admin, &g_v4_policy,
                          TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES,
                          TEE_V4_RESPONSE_ITEM_BYTES) != 0) return -1;
    tee_v4_admin_set_writeback(&g_v5_admin.v4, &g_v4_writeback);
    tee_v4_admin_set_metadata_intake(&g_v5_admin.v4,
                                     tee_v5_intake_active_metadata,
                                     &g_v4_policy);
    tee_v5_admin_set_abort_handler(&g_v5_admin, tee_v5_abort_active_handler, NULL);
    tee_v5_admin_set_delete_handler(&g_v5_admin, tee_v5_delete_chunk_handler,
                                    &g_v4_policy);
    submit = api->register_admin_hook(ssd, TEE_V4_ADMIN_SUBMIT_OPCODE,
                                     tee_v5_admin_condition,
                                     tee_v5_admin_callback, NULL);
    if (submit < 0) return tee_v5_init_failed();
    fetch = api->register_admin_hook(ssd, TEE_V4_ADMIN_FETCH_OPCODE,
                                    tee_v5_admin_condition,
                                    tee_v5_admin_callback, NULL);
    if (fetch < 0) {
        api->unregister_admin_hook(ssd, submit);
        return tee_v5_init_failed();
    }
    if (api->register_admin_hook(ssd, TEE_V4_ADMIN_CONTINUE_OPCODE,
                                 tee_v5_admin_condition,
                                 tee_v5_admin_callback, NULL) < 0) {
        api->unregister_admin_hook(ssd, fetch);
        api->unregister_admin_hook(ssd, submit);
        return tee_v5_init_failed();
    }
    return 0;
}
