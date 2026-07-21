#define TEE_V2_POLICY 1
#define TEE_V3_POLICY 1
#define init_policy tee_v4_base_init_policy
#include "tee-ftl-v1-policy.c"
#undef init_policy

#include "tee-ftl-v4-policy.h"
#include "tee-ftl-v2-policy.h"
#include "tee/tee-v4-admin.h"
#include "tee/tee-v3-policy.h"
#include "tee/tee-v4-writeback.h"

#include <stdlib.h>
#include <string.h>

#define TEE_V4_RESPONSE_ITEM_BYTES (1024U * 1024U)
#define TEE_V4_TRANSACTION_SINK_CAPACITY 64U

typedef struct __attribute__((packed)) TeeV4NvmeCmd {
    uint16_t opcode_flags;
    uint16_t cid;
    uint32_t nsid;
    uint64_t rsvd2;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} TeeV4NvmeCmd;

static struct tee_v4_admin g_v4_admin;
static struct tee_v3_storage g_v4_storage;
static struct tee_v3_memory_backend g_v4_backend;
static struct tee_v3_policy_context g_v4_policy;
static struct tee_v4_writeback g_v4_writeback;
static struct tee_v4_transaction_record
    g_v4_pending_transactions[TEE_V4_DEFAULT_RELOCATION_BATCH_MAX];
static struct tee_v4_transaction_record
    g_v4_transaction_sink[TEE_V4_TRANSACTION_SINK_CAPACITY];
static uint32_t g_v4_transaction_sink_count;

static int tee_v4_flush_transactions(
    void *opaque, const struct tee_v4_transaction_record *records,
    uint32_t count)
{
    struct tee_v3_policy_context *policy = opaque;
    uint32_t i;
    bool has_relocation = false;
    if (!records || !policy || !policy->write || !policy->write->cache ||
        !policy->storage) {
        return -1;
    }
    for (i = 0; i < count; i++) {
        if (records[i].type == TEE_V4_TRANSACTION_RELOCATION) {
            has_relocation = true;
        }
    }
    if (has_relocation &&
        tee_v3_storage_persist(
            policy->storage, &policy->write->cache->protected_bitmap,
            policy->write->cache->passive_records,
            policy->write->cache->passive_count) != 0) {
        return -1;
    }
    for (i = 0; i < count; i++) {
        uint32_t slot = g_v4_transaction_sink_count %
                        TEE_V4_TRANSACTION_SINK_CAPACITY;
        g_v4_transaction_sink[slot] = records[i];
        g_v4_transaction_sink[slot].state =
            TEE_V4_TRANSACTION_PERSISTED;
        g_v4_transaction_sink_count++;
    }
    return 0;
}

static int tee_v4_persist_promotion(
    void *opaque, const struct tee_v2_cache *cache,
    const struct tee_v2_passive_metadata *passive)
{
    struct tee_v3_policy_context *policy = opaque;
    int result;
    if (tee_v3_policy_persist_promotion(policy, cache, passive) != 0) {
        return -1;
    }
    result = tee_v4_writeback_commit_chunk(
        &g_v4_writeback, passive->file_id, passive->chunk_id);
    if (result != 0) {
        /* V3 is already durable. Keep promotion monotonic and expose the
         * audit/writeback failure through the pending controller and SYNC.
         */
        tee_v3_pending_record_error(&policy->pending, result, 0);
    }
    return 0;
}

static int tee_v4_record_relocation(void *opaque, uint8_t file_id,
                                    uint32_t chunk_id,
                                    uint32_t segment_index,
                                    uint64_t old_location,
                                    uint64_t new_location)
{
    return tee_v4_writeback_reserve_relocation(
        opaque, file_id, chunk_id, segment_index, old_location, new_location);
}

static int tee_v4_advance_operation(void *opaque, uint64_t ops)
{
    return tee_v4_writeback_advance(opaque, ops);
}

static int tee_v4_cancel_relocations(void *opaque, uint32_t count)
{
    return tee_v4_writeback_cancel_reserved(opaque, count);
}

static int tee_v4_intake_active_metadata(
    void *opaque,
    const struct tee_v4_admin_active_metadata_payload *metadata,
    const struct tee_v4_admin_hmac_group_wire *groups)
{
    struct tee_v2_hmac_group_spec *specs = NULL;
    uint32_t i;
    int result;
    (void)opaque;
    if (g_v4_policy.pending.reject_active_supersession && g_v2_active_valid &&
        (g_v2_active.file_id != metadata->file_id ||
         g_v2_active.chunk_id != metadata->chunk_id))
        return 2;
    if (metadata->group_count) {
        specs = calloc(metadata->group_count, sizeof(*specs));
        if (!specs) return -1;
    }
    for (i = 0; i < metadata->group_count; i++) {
        specs[i].start_segment_index = groups[i].start_segment_index;
        specs[i].group_segment_count = groups[i].group_segment_count;
        specs[i].expected_hmac = groups[i].expected_hmac;
    }
    if (g_ctx) {
        result = tee_v2_policy_set_active_metadata(
            metadata->file_id, metadata->chunk_id,
            metadata->chunk_size_bytes, metadata->segment_count,
            metadata->number_coefficient, specs, metadata->group_count);
    } else {
        struct tee_v2_active_metadata replacement = {0};
        result = -1;
        if (tee_v2_write_can_activate_identity(
                &g_v2_write, metadata->file_id, metadata->chunk_id) &&
            tee_v2_active_metadata_init(
                &replacement, &g_v2_config, metadata->file_id,
                metadata->chunk_id, metadata->chunk_size_bytes,
                metadata->segment_count, metadata->number_coefficient,
                specs, metadata->group_count) == 0) {
            if (g_v2_active_valid) {
                tee_v2_write_abandon_active(&g_v2_write);
                tee_v2_active_metadata_destroy(&g_v2_active);
            }
            g_v2_active = replacement;
            g_v2_active_valid = true;
            g_v2_write.active = &g_v2_active;
            g_v2_write.active_promoted = false;
            result = 0;
        }
    }
    free(specs);
    return result;
}

static int tee_v4_write_hidden_image(void *opaque, const uint8_t *data,
                                     size_t size)
{
    struct tee_v3_memory_backend *backend = opaque;

    if (!backend || size > backend->capacity) {
        return -1;
    }
    memcpy(backend->bytes, data, size);
    backend->size = size;
    return 0;
}

static bool tee_v4_admin_condition(struct ssd *ssd,
                                   struct NvmeCommandEvent *event,
                                   struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->is_admin &&
           (event->opcode == TEE_V4_ADMIN_SUBMIT_OPCODE ||
            event->opcode == TEE_V4_ADMIN_FETCH_OPCODE ||
            event->opcode == TEE_V4_ADMIN_CONTINUE_OPCODE);
}

static uint64_t tee_v4_admin_callback(struct ssd *ssd,
                                      struct NvmeCommandEvent *event,
                                      struct FtlPolicyAPI *api, void *context)
{
    const TeeV4NvmeCmd *cmd = event->cmd;
    uint32_t length;
    uint8_t *buffer = NULL;
    uint8_t *response = NULL;
    size_t written = 0;

    (void)ssd;
    (void)context;
    if (!cmd || !api || !api->read_cmd_buffer || !api->write_cmd_buffer) {
        event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        return 0;
    }

    length = cmd->cdw12;
    if (length == 0 || length > TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }
    buffer = calloc(1, length);
    if (!buffer) {
        event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        return 0;
    }

    if (event->opcode == TEE_V4_ADMIN_SUBMIT_OPCODE) {
        int submit_result;
        event->status = api->read_cmd_buffer(event, buffer, length);
        if (event->status == NVME_SUCCESS) {
            submit_result = tee_v4_admin_submit(&g_v4_admin, buffer, length);
            if (submit_result == -2) {
                event->status = NVME_INTERNAL_DEV_ERROR;
            } else if (submit_result != 0) {
                event->status = NVME_INVALID_FIELD | NVME_DNR;
            }
        }
        free(buffer);
        return 0;
    }

    event->status = api->read_cmd_buffer(event, buffer, length);
    if (event->status != NVME_SUCCESS) {
        free(buffer);
        return 0;
    }
    response = calloc(1, TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES);
    if (!response) {
        free(buffer);
        event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        return 0;
    }

    if (event->opcode == TEE_V4_ADMIN_FETCH_OPCODE) {
        if (tee_v4_admin_fetch(&g_v4_admin, buffer, length, response,
                               TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES,
                               &written) != 0) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
        } else {
            event->status = api->write_cmd_buffer(event, response,
                                                  (uint32_t)written);
        }
        free(response);
        free(buffer);
        return 0;
    }

    if (tee_v4_admin_continue(&g_v4_admin, buffer, length, response,
                              TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES,
                              &written) != 0) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
    } else {
        event->status = api->write_cmd_buffer(event, response,
                                              (uint32_t)written);
    }
    free(response);
    free(buffer);
    return 0;
}

int tee_v4_policy_state_init(struct ssd *ssd, struct FtlPolicyAPI *api)
{
    if (tee_v4_base_init_policy(ssd, api) != 0 || !api) {
        return -1;
    }
    g_v4_backend.capacity = (size_t)(g_v1_layout.hidden_lba_count *
                                     g_v1_layout.lba_size);
    g_v4_backend.bytes = calloc(g_v4_backend.capacity, 1);
    if (!g_v4_backend.bytes ||
        tee_v3_storage_init(&g_v4_storage, &g_v1_layout,
                            tee_v4_write_hidden_image, &g_v4_backend) != 0) {
        return -1;
    }
    tee_v3_policy_context_init(&g_v4_policy, &g_v2_write, &g_v4_storage);
    g_v4_transaction_sink_count = 0;
    if (tee_v4_writeback_init(
            &g_v4_writeback, g_v4_pending_transactions,
            TEE_V4_DEFAULT_RELOCATION_BATCH_MAX,
            TEE_V4_DEFAULT_RELOCATION_TIMEOUT_OPS,
            tee_v4_flush_transactions, &g_v4_policy) != 0) {
        return -1;
    }
    tee_v2_write_set_promotion_hook(&g_v2_write,
                                    tee_v4_persist_promotion,
                                    &g_v4_policy);
    tee_v2_write_set_relocation_observer(&g_v2_write,
                                         tee_v4_record_relocation,
                                         &g_v4_writeback);
    tee_v2_write_set_operation_advance(&g_v2_write,
                                       tee_v4_advance_operation,
                                       &g_v4_writeback);
    tee_v2_write_set_relocation_cancel(&g_v2_write,
                                       tee_v4_cancel_relocations,
                                       &g_v4_writeback);

    return 0;
}

#ifndef TEE_V4_POLICY_INIT_NAME
#define TEE_V4_POLICY_INIT_NAME init_policy
#endif
int TEE_V4_POLICY_INIT_NAME(struct ssd *ssd, struct FtlPolicyAPI *api)
{
    int submit_handle;
    int fetch_handle;

    if (!api || !api->register_admin_hook || !api->unregister_admin_hook ||
        tee_v4_policy_state_init(ssd, api) != 0) {
        return -1;
    }

    if (tee_v4_admin_init(&g_v4_admin, &g_v4_policy,
                          TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES,
                          TEE_V4_RESPONSE_ITEM_BYTES) != 0) {
        return -1;
    }
    tee_v4_admin_set_writeback(&g_v4_admin, &g_v4_writeback);
    tee_v4_admin_set_metadata_intake(&g_v4_admin,
                                     tee_v4_intake_active_metadata, NULL);

    submit_handle = api->register_admin_hook(
        ssd, TEE_V4_ADMIN_SUBMIT_OPCODE, tee_v4_admin_condition,
        tee_v4_admin_callback, NULL);
    if (submit_handle < 0) {
        return -1;
    }
    fetch_handle = api->register_admin_hook(
        ssd, TEE_V4_ADMIN_FETCH_OPCODE, tee_v4_admin_condition,
        tee_v4_admin_callback, NULL);
    if (fetch_handle < 0) {
        api->unregister_admin_hook(ssd, submit_handle);
        return -1;
    }
    if (api->register_admin_hook(
            ssd, TEE_V4_ADMIN_CONTINUE_OPCODE, tee_v4_admin_condition,
            tee_v4_admin_callback, NULL) < 0) {
        api->unregister_admin_hook(ssd, fetch_handle);
        api->unregister_admin_hook(ssd, submit_handle);
        return -1;
    }
    return 0;
}
