#ifndef TEE_V4_ADMIN_H
#define TEE_V4_ADMIN_H

#include "tee-v3-policy.h"
#include "tee-v4-admin-response.h"
#include "tee-v4-writeback.h"

#include <stddef.h>
#include <stdint.h>

struct tee_v4_admin {
    struct tee_v3_policy_context *policy;
    struct tee_v4_admin_response pending;
    uint32_t admin_buffer_bytes;
    struct tee_v4_writeback *writeback;
    int (*metadata_intake)(
        void *opaque,
        const struct tee_v4_admin_active_metadata_payload *metadata,
        const struct tee_v4_admin_hmac_group_wire *groups);
    void *metadata_intake_opaque;
    uint64_t last_submit_request_id;
    bool has_last_submit_request_id;
};

int tee_v4_admin_init(struct tee_v4_admin *admin,
                      struct tee_v3_policy_context *policy,
                      uint32_t admin_buffer_bytes,
                      size_t response_item_bytes);
void tee_v4_admin_destroy(struct tee_v4_admin *admin);
void tee_v4_admin_set_writeback(struct tee_v4_admin *admin,
                                struct tee_v4_writeback *writeback);
void tee_v4_admin_set_metadata_intake(
    struct tee_v4_admin *admin,
    int (*intake)(void *,
                  const struct tee_v4_admin_active_metadata_payload *,
                  const struct tee_v4_admin_hmac_group_wire *),
    void *opaque);
int tee_v4_admin_sign_request(void *request_buffer, size_t request_bytes);
int tee_v4_admin_submit(struct tee_v4_admin *admin, const void *request_buffer,
                        size_t request_bytes);
int tee_v4_admin_fetch(struct tee_v4_admin *admin, const void *request_buffer,
                       size_t request_bytes, void *response_buffer,
                       size_t response_capacity, size_t *written);
int tee_v4_admin_continue(struct tee_v4_admin *admin,
                          const void *request_buffer, size_t request_bytes,
                          void *response_buffer,
                          size_t response_capacity, size_t *written);

#endif
