#include "tee-v5-admin.h"

#include <string.h>

static int prepare_status(struct tee_v5_admin *admin,
                          const struct tee_v4_admin_request_header *header,
                          enum tee_v5_status status)
{
    return tee_v4_admin_response_prepare_items(
        &admin->v4.pending, header->command_type, header->request_id,
        status, NULL, 0, 0, 1);
}

int tee_v5_admin_init(struct tee_v5_admin *admin,
                      struct tee_v3_policy_context *policy,
                      uint32_t admin_buffer_bytes,
                      size_t response_item_bytes)
{
    if (!admin) return -1;
    memset(admin, 0, sizeof(*admin));
    if (policy) {
        policy->pending.error_precedes_passive = true;
        policy->pending.reject_active_supersession = true;
    }
    return tee_v4_admin_init(&admin->v4, policy, admin_buffer_bytes,
                             response_item_bytes);
}

void tee_v5_admin_destroy(struct tee_v5_admin *admin)
{
    if (!admin) return;
    tee_v4_admin_destroy(&admin->v4);
    memset(admin, 0, sizeof(*admin));
}

void tee_v5_admin_set_abort_handler(struct tee_v5_admin *admin,
                                    tee_v5_abort_active_fn handler,
                                    void *opaque)
{
    if (!admin) return;
    admin->abort_active = handler;
    admin->abort_active_opaque = opaque;
}

void tee_v5_admin_set_delete_handler(struct tee_v5_admin *admin,
                                     tee_v5_delete_fn handler, void *opaque)
{
    if (!admin) return;
    admin->delete_chunk = handler;
    admin->delete_chunk_opaque = opaque;
}

int tee_v5_admin_submit(struct tee_v5_admin *admin, const void *request,
                        size_t request_bytes)
{
    const struct tee_v4_admin_request_header *header = request;
    const struct tee_v5_chunk_identity_payload *identity;
    int callback_result;

    if (!admin || tee_v4_admin_verify_request(request, request_bytes) != 0 ||
        header->flags != TEE_V4_ADMIN_FLAG_SUBMIT ||
        (admin->v4.has_last_submit_request_id &&
         header->request_id <= admin->v4.last_submit_request_id)) {
        return -1;
    }
    if (header->command_type < TEE_V5_ADMIN_CMD_DELETE) {
        return tee_v4_admin_submit(&admin->v4, request, request_bytes);
    }
    if (header->command_type != TEE_V5_ADMIN_CMD_DELETE &&
        header->command_type != TEE_V5_ADMIN_CMD_ABORT_ACTIVE) {
        callback_result = prepare_status(admin, header,
                                         TEE_V5_STATUS_UNSUPPORTED);
    } else {
        identity = (const void *)((const uint8_t *)request + sizeof(*header));
        if (!tee_v5_chunk_identity_payload_valid(identity,
                                                  header->payload_len)) {
            return -1;
        }
        if (header->command_type == TEE_V5_ADMIN_CMD_ABORT_ACTIVE) {
            callback_result = admin->abort_active ?
                admin->abort_active(admin->abort_active_opaque,
                                    identity->file_id, identity->chunk_id) : 1;
            callback_result = prepare_status(
                admin, header, callback_result < 0 ?
                    TEE_V5_STATUS_INTERNAL_ERROR : TEE_V5_STATUS_OK);
        } else {
            int delete_result;
            callback_result = admin->delete_chunk ?
                admin->delete_chunk(admin->delete_chunk_opaque,
                                    identity->file_id, identity->chunk_id) : -1;
            delete_result = callback_result;
            callback_result = prepare_status(
                admin, header, callback_result == 0 ? TEE_V5_STATUS_OK :
                callback_result == 1 ? TEE_V5_STATUS_NOT_FOUND :
                callback_result == 2 ? TEE_V5_STATUS_BAD_REQUEST :
                TEE_V5_STATUS_INTERNAL_ERROR);
            if (callback_result == 0 && delete_result < 0) return -2;
        }
    }
    if (callback_result == 0) {
        admin->v4.last_submit_request_id = header->request_id;
        admin->v4.has_last_submit_request_id = true;
    }
    return callback_result;
}

int tee_v5_admin_fetch(struct tee_v5_admin *admin, const void *request,
                       size_t request_bytes, void *response,
                       size_t response_capacity, size_t *written)
{
    const struct tee_v4_admin_request_header *header = request;
    struct tee_v4_admin_response temporary;
    int result;

    if (!admin || tee_v4_admin_verify_request(request, request_bytes) != 0 ||
        request_bytes != sizeof(*header) || header->payload_len != 0 ||
        header->flags != TEE_V4_ADMIN_FLAG_FETCH) {
        if (written) *written = 0;
        return -1;
    }
    if (admin->v4.pending.valid &&
        admin->v4.pending.command_type == header->command_type &&
        admin->v4.pending.request_id == header->request_id) {
        return tee_v4_admin_fetch(&admin->v4, request, request_bytes,
                                  response, response_capacity, written);
    }
    memset(&temporary, 0, sizeof(temporary));
    result = tee_v4_admin_response_prepare_items(
        &temporary, header->command_type, header->request_id,
        TEE_V5_STATUS_NO_PENDING_RESPONSE, NULL, 0, 0, 1);
    if (result == 0)
        result = tee_v4_admin_response_materialize_page(
            &temporary, 0, response, response_capacity, written);
    return result;
}

int tee_v5_admin_continue(struct tee_v5_admin *admin, const void *request,
                          size_t request_bytes, void *response,
                          size_t response_capacity, size_t *written)
{
    if (!admin) return -1;
    return tee_v4_admin_continue(&admin->v4, request, request_bytes,
                                 response, response_capacity, written);
}
