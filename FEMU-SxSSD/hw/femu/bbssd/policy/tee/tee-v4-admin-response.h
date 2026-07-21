#ifndef TEE_V4_ADMIN_RESPONSE_H
#define TEE_V4_ADMIN_RESPONSE_H

#include "tee-v4-admin-format.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct tee_v4_admin_response {
    uint8_t *items;
    size_t item_bytes_capacity;
    uint32_t item_size;
    uint32_t total_items;
    uint32_t items_per_page;
    uint16_t command_type;
    uint64_t request_id;
    int32_t status;
    bool valid;
};

int tee_v4_admin_response_init(struct tee_v4_admin_response *response,
                               size_t item_bytes_capacity);
void tee_v4_admin_response_destroy(struct tee_v4_admin_response *response);
void tee_v4_admin_response_clear(struct tee_v4_admin_response *response);
int tee_v4_admin_response_prepare_items(
    struct tee_v4_admin_response *response, uint16_t command_type,
    uint64_t request_id, int32_t status, const void *items,
    uint32_t total_items, uint32_t item_size, uint32_t items_per_page);
int tee_v4_admin_response_materialize_page(
    const struct tee_v4_admin_response *response, uint32_t page_index,
    void *out, size_t out_capacity, size_t *written);

#endif
