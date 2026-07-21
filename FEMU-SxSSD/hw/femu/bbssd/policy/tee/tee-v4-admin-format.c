#include "tee-v4-admin-format.h"

#include <string.h>

bool tee_v4_admin_request_valid(
    const struct tee_v4_admin_request_header *header, size_t buffer_bytes)
{
    size_t span;

    if (!header) {
        return false;
    }
    if (header->magic != TEE_V4_ADMIN_MAGIC ||
        header->version != TEE_V4_ADMIN_VERSION) {
        return false;
    }
    return tee_v4_admin_mac_span(header, buffer_bytes, &span);
}

bool tee_v4_admin_mac_span(const struct tee_v4_admin_request_header *header,
                           size_t buffer_bytes, size_t *span_out)
{
    size_t span;

    if (!header || !span_out || buffer_bytes < sizeof(*header)) {
        return false;
    }
    span = TEE_V4_ADMIN_REQUEST_MAC_OFFSET + (size_t)header->payload_len;
    if (span < TEE_V4_ADMIN_REQUEST_MAC_OFFSET ||
        sizeof(*header) + (size_t)header->payload_len > buffer_bytes) {
        return false;
    }
    *span_out = span;
    return true;
}

uint32_t tee_v4_admin_total_pages(uint32_t total_items,
                                  uint32_t items_per_page)
{
    if (total_items == 0) {
        return 1;
    }
    if (items_per_page == 0) {
        return 0;
    }
    return (total_items + items_per_page - 1U) / items_per_page;
}

uint32_t tee_v4_admin_start_item(uint32_t page_index,
                                 uint32_t items_per_page)
{
    return page_index * items_per_page;
}

uint32_t tee_v4_admin_returned_items(uint32_t total_items,
                                     uint32_t page_index,
                                     uint32_t items_per_page)
{
    uint32_t start;

    if (items_per_page == 0) {
        return 0;
    }
    start = tee_v4_admin_start_item(page_index, items_per_page);
    if (start >= total_items) {
        return 0;
    }
    if (total_items - start < items_per_page) {
        return total_items - start;
    }
    return items_per_page;
}

void tee_v4_admin_response_header_init(
    struct tee_v4_admin_response_header *header, uint16_t command_type,
    uint64_t request_id, int32_t status, uint32_t total_items,
    uint32_t item_size, uint32_t items_per_page, uint32_t page_index)
{
    if (!header) {
        return;
    }
    memset(header, 0, sizeof(*header));
    header->magic = TEE_V4_ADMIN_MAGIC;
    header->version = TEE_V4_ADMIN_VERSION;
    header->command_type = command_type;
    header->request_id = request_id;
    header->status = status;
    header->total_items = total_items;
    header->start_item = tee_v4_admin_start_item(page_index, items_per_page);
    header->returned_items =
        tee_v4_admin_returned_items(total_items, page_index, items_per_page);
    header->item_size = item_size;
    header->total_pages = tee_v4_admin_total_pages(total_items, items_per_page);
    header->page_index = page_index;
}
