#ifndef TEE_V4_ADMIN_H
#define TEE_V4_ADMIN_H

#include "tee-v3-policy.h"
#include "tee-v4-admin-response.h"

#include <stddef.h>
#include <stdint.h>

struct tee_v4_admin {
    struct tee_v3_policy_context *policy;
    struct tee_v4_admin_response pending;
    uint32_t admin_buffer_bytes;
};

int tee_v4_admin_init(struct tee_v4_admin *admin,
                      struct tee_v3_policy_context *policy,
                      uint32_t admin_buffer_bytes,
                      size_t response_item_bytes);
void tee_v4_admin_destroy(struct tee_v4_admin *admin);
int tee_v4_admin_sign_request(void *request_buffer, size_t request_bytes);
int tee_v4_admin_submit(struct tee_v4_admin *admin, const void *request_buffer,
                        size_t request_bytes);
int tee_v4_admin_fetch(struct tee_v4_admin *admin, void *response_buffer,
                       size_t response_capacity, size_t *written);
int tee_v4_admin_continue(struct tee_v4_admin *admin, uint64_t request_id,
                          uint32_t page_index, void *response_buffer,
                          size_t response_capacity, size_t *written);

#endif
