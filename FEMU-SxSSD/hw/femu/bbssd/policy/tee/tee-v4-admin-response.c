#include "tee-v4-admin-response.h"

#include <stdlib.h>
#include <string.h>

int tee_v4_admin_response_init(struct tee_v4_admin_response *response,
                               size_t item_bytes_capacity)
{
    if (!response) {
        return -1;
    }
    memset(response, 0, sizeof(*response));
    if (item_bytes_capacity == 0) {
        return 0;
    }
    response->items = malloc(item_bytes_capacity);
    if (!response->items) {
        return -1;
    }
    response->item_bytes_capacity = item_bytes_capacity;
    return 0;
}

void tee_v4_admin_response_destroy(struct tee_v4_admin_response *response)
{
    if (!response) {
        return;
    }
    free(response->items);
    memset(response, 0, sizeof(*response));
}

void tee_v4_admin_response_clear(struct tee_v4_admin_response *response)
{
    if (!response) {
        return;
    }
    response->item_size = 0;
    response->total_items = 0;
    response->items_per_page = 0;
    response->command_type = 0;
    response->request_id = 0;
    response->status = TEE_V4_ADMIN_STATUS_NO_PENDING_RESPONSE;
    response->valid = false;
}

int tee_v4_admin_response_prepare_items(
    struct tee_v4_admin_response *response, uint16_t command_type,
    uint64_t request_id, int32_t status, const void *items,
    uint32_t total_items, uint32_t item_size, uint32_t items_per_page)
{
    size_t bytes;

    if (!response || (total_items > 0 && (!items || item_size == 0)) ||
        (total_items > 0 && items_per_page == 0)) {
        return -1;
    }
    bytes = (size_t)total_items * (size_t)item_size;
    if (item_size != 0 && bytes / item_size != total_items) {
        return -1;
    }
    if (bytes > response->item_bytes_capacity) {
        return -1;
    }
    if (bytes > 0) {
        memcpy(response->items, items, bytes);
    }
    response->item_size = item_size;
    response->total_items = total_items;
    response->items_per_page = items_per_page ? items_per_page : 1U;
    response->command_type = command_type;
    response->request_id = request_id;
    response->status = status;
    response->valid = true;
    return 0;
}

int tee_v4_admin_response_materialize_page(
    const struct tee_v4_admin_response *response, uint32_t page_index,
    void *out, size_t out_capacity, size_t *written)
{
    struct tee_v4_admin_response_header *header;
    uint32_t total_pages;
    uint32_t returned_items;
    uint32_t start_item;
    size_t payload_bytes;
    size_t total_bytes;
    size_t item_offset;

    if (written) {
        *written = 0;
    }
    if (!response || !response->valid || !out || !written ||
        out_capacity < sizeof(*header)) {
        return -1;
    }
    total_pages = tee_v4_admin_total_pages(response->total_items,
                                           response->items_per_page);
    if (total_pages == 0 || page_index >= total_pages) {
        return -1;
    }
    returned_items = tee_v4_admin_returned_items(response->total_items,
                                                page_index,
                                                response->items_per_page);
    start_item = tee_v4_admin_start_item(page_index,
                                         response->items_per_page);
    if (response->item_size != 0 &&
        returned_items > SIZE_MAX / response->item_size) {
        return -1;
    }
    payload_bytes = (size_t)returned_items * response->item_size;
    if (payload_bytes > SIZE_MAX - sizeof(*header)) {
        return -1;
    }
    total_bytes = sizeof(*header) + payload_bytes;
    if (total_bytes > out_capacity) {
        return -1;
    }

    header = out;
    tee_v4_admin_response_header_init(
        header, response->command_type, response->request_id,
        response->status, response->total_items, response->item_size,
        response->items_per_page, page_index);
    if (payload_bytes > 0) {
        if (response->item_size != 0 &&
            start_item > SIZE_MAX / response->item_size) {
            return -1;
        }
        item_offset = (size_t)start_item * response->item_size;
        if (item_offset > response->item_bytes_capacity ||
            payload_bytes > response->item_bytes_capacity - item_offset) {
            return -1;
        }
        memcpy((uint8_t *)out + sizeof(*header),
               response->items + item_offset,
               payload_bytes);
    }
    *written = total_bytes;
    return 0;
}
