#define TEE_V2_POLICY 1
#define TEE_V3_POLICY 1
#define init_policy tee_v4_base_init_policy
#include "tee-ftl-v1-policy.c"
#undef init_policy

#include "tee-ftl-v4-policy.h"
#include "tee/tee-v4-admin.h"
#include "tee/tee-v3-policy.h"

#include <stdlib.h>
#include <string.h>

#define TEE_V4_RESPONSE_ITEM_BYTES (1024U * 1024U)

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
        event->status = api->read_cmd_buffer(event, buffer, length);
        if (event->status == NVME_SUCCESS &&
            tee_v4_admin_submit(&g_v4_admin, buffer, length) != 0) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
        }
        free(buffer);
        return 0;
    }

    if (event->opcode == TEE_V4_ADMIN_FETCH_OPCODE) {
        if (tee_v4_admin_fetch(&g_v4_admin, buffer, length, &written) != 0) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
        } else {
            event->status = api->write_cmd_buffer(event, buffer,
                                                  (uint32_t)written);
        }
        free(buffer);
        return 0;
    }

    event->status = api->read_cmd_buffer(event, buffer, length);
    if (event->status == NVME_SUCCESS) {
        const struct tee_v4_admin_continue_payload *payload =
            (const struct tee_v4_admin_continue_payload *)buffer;
        uint8_t *response;

        if (length != sizeof(*payload)) {
            event->status = NVME_INVALID_FIELD | NVME_DNR;
        } else {
            response = calloc(1, TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES);
            if (!response) {
                event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
            } else if (tee_v4_admin_continue(
                           &g_v4_admin, payload->request_id,
                           payload->page_index, response,
                           TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES,
                           &written) != 0) {
                event->status = NVME_INVALID_FIELD | NVME_DNR;
            } else {
                event->status = api->write_cmd_buffer(event, response,
                                                      (uint32_t)written);
            }
            free(response);
        }
    }
    free(buffer);
    return 0;
}

int init_policy(struct ssd *ssd, struct FtlPolicyAPI *api)
{
    int submit_handle;
    int fetch_handle;

    if (tee_v4_base_init_policy(ssd, api) != 0 || !api ||
        !api->register_admin_hook || !api->unregister_admin_hook) {
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
    tee_v2_write_set_promotion_hook(&g_v2_write,
                                    tee_v3_policy_persist_promotion,
                                    &g_v4_policy);

    if (tee_v4_admin_init(&g_v4_admin, &g_v4_policy,
                          TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES,
                          TEE_V4_RESPONSE_ITEM_BYTES) != 0) {
        return -1;
    }

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
