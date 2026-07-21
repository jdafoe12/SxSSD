#ifndef TEE_V5_ADMIN_H
#define TEE_V5_ADMIN_H

#include "tee-v4-admin.h"
#include "tee-v5-admin-format.h"
#include "tee-v5-status.h"

typedef int (*tee_v5_abort_active_fn)(void *opaque, uint8_t file_id,
                                      uint32_t chunk_id);
typedef int (*tee_v5_delete_fn)(void *opaque, uint8_t file_id,
                                uint32_t chunk_id);

struct tee_v5_admin {
    struct tee_v4_admin v4;
    tee_v5_abort_active_fn abort_active;
    void *abort_active_opaque;
    tee_v5_delete_fn delete_chunk;
    void *delete_chunk_opaque;
};

int tee_v5_admin_init(struct tee_v5_admin *admin,
                      struct tee_v3_policy_context *policy,
                      uint32_t admin_buffer_bytes,
                      size_t response_item_bytes);
void tee_v5_admin_destroy(struct tee_v5_admin *admin);
void tee_v5_admin_set_abort_handler(struct tee_v5_admin *admin,
                                    tee_v5_abort_active_fn handler,
                                    void *opaque);
void tee_v5_admin_set_delete_handler(struct tee_v5_admin *admin,
                                     tee_v5_delete_fn handler, void *opaque);
int tee_v5_admin_submit(struct tee_v5_admin *admin, const void *request,
                        size_t request_bytes);
int tee_v5_admin_fetch(struct tee_v5_admin *admin, const void *request,
                       size_t request_bytes, void *response,
                       size_t response_capacity, size_t *written);
int tee_v5_admin_continue(struct tee_v5_admin *admin, const void *request,
                          size_t request_bytes, void *response,
                          size_t response_capacity, size_t *written);

#endif
